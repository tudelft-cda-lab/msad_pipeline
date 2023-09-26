import pandas as pd
from statistics import fmean, stdev
from collections import Counter
import matplotlib.pyplot as plt
from datetime import datetime
from utils import ts_to_epoch
import argparse as ap
from flexfringe import FlexFringe
import os
from tqdm import tqdm

SERVICE_IPS = ['192.168.247.4', '192.168.84.144', '192.168.235.192', '192.168.235.193', '192.168.247.12', '10.106.147.84', '192.168.247.0', '10.0.2.15', '192.168.247.11', '192.168.84.151', '10.96.0.10', '192.168.84.149', '10.98.34.177', '192.168.84.146', '192.168.247.17', '192.168.247.6', '192.168.247.14', '10.96.0.1', '192.168.84.150', '192.168.247.1', '192.168.84.133', '192.168.84.132', '192.168.247.7', '192.168.247.9', '192.168.247.8', '192.168.247.10', '192.168.84.147', '192.168.247.5', '192.168.247.15', '192.168.247.16']

def state_sequence_to_list(trace):
    print(trace)
    return trace.replace('[', '').replace(']', '').strip().split(',')

# def scores_to_list(trace):
#     return [float(x) for x in trace.replace('[', '').replace(']', '').strip().split(',')]

def scores_to_list(trace):
    return [float(x) for x in trace]

def compute_rc_from_probability_scores(probability_scores, state_sequences):
    root_causes = []
    rc_indices = []
    for i in range(len(probability_scores)):
        rc_index = probability_scores[i].index(min(probability_scores[i]))
        rc = state_sequences[i][rc_index]
        root_causes.append(rc)
        rc_indices.append(rc_index)
    return root_causes, rc_indices

def group_prediction_by_rc(predictions, root_causes):
    grouped_predictions = dict()
    for i in range(len(predictions)):
        rc = root_causes[i]
        if rc not in grouped_predictions:
            grouped_predictions[rc] = []
        grouped_predictions[rc].append(predictions[i])
    
    return grouped_predictions

def convert_grouped_predictions_to_df(grouped_predictions, column_names):
    rc_to_df_mapping = dict()
    for rc in grouped_predictions:
        rc_to_df_mapping[rc] = pd.DataFrame(grouped_predictions[rc], columns=column_names)

    return rc_to_df_mapping

def compute_top_10_rc(predictions):
    rc = predictions['root cause symbol'].tolist()
    rc_counter = Counter(rc)
    top_10_rc = rc_counter.most_common(10)
    return top_10_rc

def find_ip_and_port_from_rc(data, rc_data, service_ip):
    ip_port_info = []
    csv_row_numbers = rc_data['first row nr'].tolist()
    rc_indices = rc_data['root cause index'].tolist()
    dst_port = data['dst_port'].tolist()
    src_ip = data['src_ip'].tolist()
    dst_ip = data['dst_ip'].tolist()
    time_stamps = data['timestamp'].tolist()
    connection_info_to_first_time_seen = dict()

    for i in range(len(csv_row_numbers)):
        row_number_for_rc = csv_row_numbers[i] + rc_indices[i]
        time_stamp = time_stamps[row_number_for_rc]
        connection_info_text = '' 
        if src_ip[row_number_for_rc] == service_ip:
            connection_info_text += 'outbound_' + str(dst_ip[row_number_for_rc]) + '_' + str(dst_port[row_number_for_rc])
        elif dst_ip[row_number_for_rc] == service_ip:
            connection_info_text += 'inbound_' + str(src_ip[row_number_for_rc]) + '_' + str(dst_port[row_number_for_rc])
            
        ip_port_info.append(connection_info_text)
        if connection_info_text not in connection_info_to_first_time_seen:
            connection_info_to_first_time_seen[connection_info_text] = time_stamp
        else:
            if time_stamp < connection_info_to_first_time_seen[connection_info_text]:
                connection_info_to_first_time_seen[connection_info_text] = time_stamp
    
    connection_frequency = Counter(ip_port_info)
    sorted_connection = sorted(connection_frequency.items(), key=lambda x: x[1], reverse=True)
    rc_connection_info = []
    for connection in sorted_connection:
        info = connection[0].split('_')
        frequency = connection[1]
        first_time_seen = datetime.fromtimestamp(connection_info_to_first_time_seen[connection[0]]).strftime('%Y-%m-%dT%H:%M:%S')
        rc_connection_info.append([info[0], info[1], info[2], frequency, first_time_seen])
    
    rc_connection_info_df = pd.DataFrame(rc_connection_info, columns=['direction', 'ip', 'port', 'number of times flagged as root cause', 'first time seen'])
    return rc_connection_info_df

def plot_scores(anomaly_scores, output_folder, type, threshold=None, colours=None):
    plt.ylim(1, -100)
    if colours is not None and threshold is not None:
        plt.bar(list(range(0, len(anomaly_scores))), anomaly_scores, color=colours)
        #plot line for threshold
        plt.axhline(y=threshold, color='r', linestyle='-')
    else:
        plt.bar(list(range(0, len(anomaly_scores))), anomaly_scores)
    plt.xlabel('Trace number')
    plt.ylabel('Log-likelihood probability')
    plt.xlim(left=0)
    plt.savefig(output_folder + 'probability_plot_' + type + '.png')
    plt.clf()
    plt.cla()


def check_for_anomalies(predictions, score_column, alarm_threshold):
    """
    Check for anomalies in the predictions. If the prediciton
    is below the alarm threshold (because the loglikelihood 
    probability is negative), then we consider it as an anomaly.
    """
    anomalies = []
    for p in predictions:
        if p[score_column] < alarm_threshold:
            # print('ANOMALY DETECTED')
            anomalies.append(1)
        else:
            anomalies.append(0)
    
    return anomalies

def monitor(service_ip):
    ff = FlexFringe(
        flexfringe_path= os.environ['FLEXFRINGE_PATH'] + '/flexfringe',
        ini='monitoring.ini'
    )
    service_train_data_folder = 'train_data/' + service_ip + '/'
    service_monitor_data_folder = 'monitor_data/' + service_ip + '/'
    model_path = service_train_data_folder + service_ip + '_train_data.csv.ff.final.json'
    train_predictions = pd.read_csv(service_train_data_folder + 'train_data_predictions.csv', delimiter=',')
    service_monitor_data_predictions = ff.predict(service_monitor_data_folder  + service_ip + '_monitor_data.csv', model_path)
    service_monitor_netflow_data = pd.read_csv(service_monitor_data_folder + service_ip + '_monitor_data.csv', delimiter=',')
    service_monitor_netflow_data['timestamp'] = ts_to_epoch(service_monitor_netflow_data['timestamp'])

    train_probabilities = train_predictions['sum scores'].tolist()
    avg_prob = fmean(train_probabilities)
    std_prob = stdev(train_probabilities)
    alarm_threshold = avg_prob - (7.0 * std_prob)
    score_column = train_predictions.columns.tolist().index('sum scores')
    prediction = check_for_anomalies(service_monitor_data_predictions.values, score_column, alarm_threshold)

    anomalous_predictions = []
    for i in range(len(prediction)):
        if prediction[i] == 1:
            anomalous_predictions.append(i)

    anomalous_predictions_df = service_monitor_data_predictions.iloc[anomalous_predictions].copy()
    state_sequences = anomalous_predictions_df['state sequence'].tolist()
    score_sequences = anomalous_predictions_df['score sequence'].apply(scores_to_list).tolist()
    root_causes, rc_indices = compute_rc_from_probability_scores(score_sequences, state_sequences)
    anomalous_predictions_df['root cause symbol'] = root_causes
    anomalous_predictions_df['root cause index'] = rc_indices
    top10_rc = compute_top_10_rc(anomalous_predictions_df)
    grouped_predictions = group_prediction_by_rc(anomalous_predictions_df.values, root_causes)
    grouped_predictions_dfs = convert_grouped_predictions_to_df(grouped_predictions, anomalous_predictions_df.columns.tolist())

    for rc in top10_rc:
        rc_predictions = grouped_predictions_dfs[rc[0]]
        rc_predictions.to_csv(service_monitor_data_folder + 'root_cause_' + rc[0] + '_prediction_info.csv', sep=';', index=False)
        connection_info_df = find_ip_and_port_from_rc(service_monitor_netflow_data, rc_predictions, service_ip)
        connection_info_df.to_csv(service_monitor_data_folder + 'root_cause_' + rc[0] + '_connection_info.csv', sep=';', index=False)

    colours = ['red' if x < alarm_threshold else 'blue' for x in service_monitor_data_predictions['sum scores'].tolist()]
    plot_scores(service_monitor_data_predictions['sum scores'].tolist(), service_monitor_data_folder, 'monitor', threshold=alarm_threshold, colours=colours)


def train(service_ip):
    ff = FlexFringe(
        flexfringe_path= os.environ.get('FLEXFRINGE_PATH') + '/flexfringe',
        ini='likelihood.ini',
    )

    service_data_folder = 'train_data/' + service_ip + '/'
    service_train_data = service_data_folder + service_ip + '_train_data.csv'
    ff.fit(service_data_folder + service_ip + '_train_data.csv')
    training_predictions = ff.predict(service_train_data)
    training_predictions.to_csv(service_data_folder + 'train_data_predictions.csv', sep=',', index=False)
    plot_scores(training_predictions['sum scores'].tolist(), service_data_folder, 'train')



arg_parser = ap.ArgumentParser()
arg_parser.add_argument('--mode', required=True, help='The mode to be used (either train or monitor).')
arg_parser.add_argument('--train_data_path', required=False, help='Path to the folder containing training data.')
arg_parser.add_argument('--monitor_data_path', required=False, help='Path to the folder containing data to be monitored.')
arg_parser = arg_parser.parse_args()

if arg_parser.mode == 'train':
    print('Training mode selected')
    for ip in tqdm(SERVICE_IPS):
        train(ip)
elif arg_parser.mode == 'monitor':
    print('Monitoring mode selected')
    for ip in tqdm(SERVICE_IPS):
        monitor(ip)






