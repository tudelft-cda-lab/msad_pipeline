# import argparse as ap
from flexfringe import FlexFringe
import utils
from statistics import fmean, stdev
import os
import pandas as pd
# from loguru import logger
# import time
from collections import Counter
import matplotlib.pyplot as plt
import math

# logger.enable('flexfringe')

def state_sequence_to_list(trace):
    '''
    Parse a state sequence produced by FlexFringe into a list
    '''
    return trace.replace('[', '').replace(']', '').strip().split(',')

def anomaly_scores_to_list(trace):
    '''
    Parse a list of anomaly scores produced by FlexFringe into a list
    '''
    return [float(x) for x in trace.replace('[', '').replace(']', '').strip().split(',')]

def compute_rc_from_anomaly_scores(anomaly_scores, state_sequences):
    '''
    Compute the root causes for the given trances and their anomaly scores
    '''
    root_causes = []
    rc_indices = []
    for i in range(len(state_sequences)):
        rc_index = anomaly_scores[i].index(max(anomaly_scores[i]))
        rc = state_sequences[i][rc_index]
        root_causes.append(rc)
        rc_indices.append(rc_index)
    return root_causes, rc_indices

def group_prediction_by_rc(predictions, root_causes):
    '''
    Group the predictions of FlexFringe based on the root causes their root causes
    '''
    grouped_predictions = dict()
    for i in range(len(predictions)):
        rc = root_causes[i]
        if rc not in grouped_predictions:
            grouped_predictions[rc] = []
        grouped_predictions[rc].append(predictions[i])
    
    return grouped_predictions

def convert_grouped_predictions_to_df(grouped_predictions, column_names):
    '''
    Convert the grouped predictions (grouped by root causes) to a dictionary of DataFrames.
    With each root cause you can get the predictions in a DataFrame format.
    '''
    rc_to_df_mapping = dict()
    for rc in grouped_predictions:
        rc_to_df_mapping[rc] = pd.DataFrame(grouped_predictions[rc], columns=column_names)

    return rc_to_df_mapping


def compute_top_10_rc(predictions):
    '''
    Compute the top 10 root causes from the given predictions.
    '''
    rc = predictions['root cause symbol'].tolist()
    rc_counter = Counter(rc)
    top_10_rc = rc_counter.most_common(10)
    return top_10_rc

def find_ip_and_port_from_rc(data, rc_data, current_service_ip):
    '''
    Find the IP and port information for the given root causes. This is done by finding 
    the corresponding row in the NetFlow data using the root cause information.
    '''
    ip_port_info = []
    csv_row_numbers = rc_data['first row nr'].tolist()
    rc_indices = rc_data['root cause index'].tolist()
    dst_port = data['dst_port'].tolist()
    src_ip = data['src_ip'].tolist()
    dst_ip = data['dst_ip'].tolist()

    for i in range(len(csv_row_numbers)):
        row_number_for_rc = csv_row_numbers[i] + rc_indices[i]
        connection_info_text = '' 
        if src_ip[row_number_for_rc] == current_service_ip:
            connection_info_text += 'outbound_' + dst_ip[row_number_for_rc] + '_' + str(dst_port[row_number_for_rc])
        elif dst_ip[row_number_for_rc] == current_service_ip:
            connection_info_text += 'inbound_' + src_ip[row_number_for_rc] + '_' + str(dst_port[row_number_for_rc])
            
        ip_port_info.append(connection_info_text)
    
    connection_frequency = Counter(ip_port_info)
    sorted_connection = sorted(connection_frequency.items(), key=lambda x: x[1], reverse=True)
    rc_connection_info = []
    for connection in sorted_connection:
        info = connection[0].split('_')
        frequency = connection[1]
        rc_connection_info.append([info[0], info[1], info[2], frequency])
    
    rc_connection_info_df = pd.DataFrame(rc_connection_info, columns=['direction', 'ip', 'port', 'number of times flagged as root cause'])
    return rc_connection_info_df

def plot_anomaly_scores(anomaly_scores):
    '''
    Plot the anomaly scores using a bar chart.
    '''
    plt.bar(list(range(0, len(anomaly_scores))), anomaly_scores)
    plt.xlabel('Trace number')
    plt.ylabel('Anomaly score')
    plt.xlim(left=0)
    plt.ylim(bottom=0)
    plt.show()


def compute_state_frequencies(state_sequences):
    '''
    Compute the frequency of each state given the state sequences that were traversed.
    This is used on training data.
    '''
    states = []
    for state_sequence in state_sequences:
        states += state_sequence

    return Counter(states)

def compute_expectation_of_state(state_frequencies):
    '''
    Compute the expectation of a state given the state frequencies.
    This is used on training data.
    '''
    state_expectations = dict()
    total_count = sum(state_frequencies.values())
    for state in state_frequencies:
        state_expectations[state] = state_frequencies[state] / total_count
    
    return state_expectations

def compute_rolling_anomaly_score(test_state_sequences, state_frequency_train):
    '''
    Compute the rolling anomaly score using the frequency of the states. It is called 
    the rolling anomaly score as it is computed for each new batch of data.
    '''
    anomaly_scores = []
    sequence_anomaly_scores = []
    test_state_counts = Counter()
    total_count_from_train = sum(state_frequency_train.values())

    for state_sequence in test_state_sequences:
        sequence_score = 0.0
        seq_anom_score = []
        for state in state_sequence:
            state_score = math.log(test_state_counts[state] + 1)
            state_score -= math.log(state_frequency_train[state] + 1)
            state_score += math.log(total_count_from_train + 1)
            state_score -= math.log(len(test_state_counts.keys()) + 1)
            test_state_counts[state] += 1
            sequence_score += state_score
            seq_anom_score.append(state_score)
        
        sequence_anomaly_scores.append(seq_anom_score)
        anomaly_scores.append(sequence_score)

    return anomaly_scores, sequence_anomaly_scores


def check_for_anomalies(predictions, score_column, alarm_threshold):
    """
    Check for anomalies in the predictions. If the prediction
    is above the alarm threshold, then we consider it as an anomaly.
    """
    predicted_labels = []
    for p in predictions:
        if p[score_column] > alarm_threshold:
            predicted_labels.append(1)
        else:
            predicted_labels.append(0)
    
    return predicted_labels


def monitor_traffic(model_path, data, deviation_factor, service_ip_folder):
    """
    Monitor the traffic and detect anomalies
    """
    print('Monitoring traffic')
    training_predictions_df = pd.read_csv(service_ip_folder + 'encoded_training_data_predictions.csv', delimiter=';')
    probabilities = training_predictions_df[' sum scores'].tolist()
    avg_prob = fmean(probabilities)
    std_prob = stdev(probabilities)
    alarm_threshold = avg_prob - (deviation_factor * std_prob)
    ff = FlexFringe(
        flexfringe_path= os.environ['FLEXFRINGE_PATH'] + '/flexfringe',
        ini='runtime_monitoring/monitoring.ini'
    )

    service_ip = service_ip_folder.split('/')[-2]
    hour_data_df = utils.json_to_df(data, service_ip)
    
    # No new data for the given service
    if hour_data_df is None:
        return

    encoded_hour_data = utils.encode_data(hour_data_df, service_ip_folder, precomputed=True)
    encoded_hour_data.to_csv(service_ip_folder + 'encoded_hour_data.csv', sep=',', index=False)
    predictions = ff.predict(service_ip_folder + 'encoded_hour_data.csv', model_path)
    prediction_columns = predictions.columns.tolist()
    score_column = prediction_columns.index('sum scores')
    anomalies = check_for_anomalies(predictions.values, score_column, alarm_threshold)
    anomalies_df = pd.DataFrame(anomalies, columns=prediction_columns)
    anomalies_df.to_csv(service_ip_folder + 'anomalies.csv', sep=',', index=False)
            

def train_model(data_path, precomputed_encoding=False):
    print('Learning model with Flexfringe')
    encoded_training_data_path = utils.preprocess_training_data(data_path, precomputed_encoding=precomputed_encoding)
    encoded_training_data_folder = '/'.join(encoded_training_data_path.split('/')[:-1]) + '/'

    ff = FlexFringe(
        flexfringe_path= os.environ.get('FLEXFRINGE_PATH') + '/flexfringe',
        ini='likelihood.ini',
    )

    ff.fit(encoded_training_data_path)
    training_predictions = ff.predict(encoded_training_data_path)
    training_predictions.to_csv(encoded_training_data_folder + 'encoded_training_data_predictions.csv', sep=',', index=False)
    print('Successfully learned model with Flexfringe')


# if __name__ == "__main__":

#     if os.environ.get('FLEXFRINGE_PATH') is None:
#         print('Path to FlexFringe is not set, please set the environment variable FLEXFRINGE_PATH to the folder where the binary of FlexFringe is located.')
#         exit()
    
#     if os.environ.get('SERVICE_IP') is None:
#         print('IP address of the service is not set, please set the environment variable SERVICE_IP to the IP address of the service.')
#         exit()
    
#     arg_parser = ap.ArgumentParser(description='Pipeline for anomaly detection using state machines')
#     arg_parser.add_argument('--traindata', type=str, help='Path to the training data for learning a state machine model. The file must be in CSV format.')
#     arg_parser.add_argument('--mode', type=str, required=True, help='Which mode should be used for the pipeline (either monitor or train). If monitor is selected, the pipeline expect a model to be already learned previous from training traces. Do not run monitor mode if you have not trained a model first.')
#     arg_parser.add_argument('--deviation_factor', type=float, default=2.0, help='Factor that is used to compute the threshold value on when an alarm should be raised. The threshold is computed as follows: thresh = avg_prob - (deviation_factor * std_prob). If probability of a trace is below the threshold, then an alarm is raised.')
#     arg_parser.add_argument('--model_path', type=str, help='Path to a pre-trained model (from FlexFringe) that should be used for monitoring. This argument must be used together with the "monitor" mode.')
#     arg_parser.add_argument('--precomputed_encoding', type=bool, default=False, help='If an encoding has already been learned for the data.')
#     args = arg_parser.parse_args()

#     if args.mode == 'train':
#         if args.traindata is None:
#             print('Please provide a path to the training data. This is required for the train mode.')
#             exit()
#         else:
#             train_model(args.traindata, args.precomputed_encoding)
#     elif args.mode == 'monitor':
#         if args.model_path is None:
#             print('Please provide a path to a pre-trained model. This is required for the monitor mode.')
#             exit()
#         else:
#             monitor_traffic(args.model_path, args.deviation_factor)
    





