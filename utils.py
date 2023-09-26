import pandas as pd
import json
from collections import Counter
from encode.encode import encode
import os
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
from datetime import datetime

es = Elasticsearch([{'host': '172.16.2.10', 'port': 9200}])

def collect_hour_data():
    """
    Collects an hour of data from the Elastic Stack
    """
    print('Collecting new batch of data')
    packetbeat_index = list(es.indices.get_alias('packetbeat-*'))[0]

    print('Collecting hour data')
    query_results = scan(es,
        index=packetbeat_index,
        preserve_order=True,
        query={
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "now-1h",
                        "lt": "now"
                        }
                    }
                }
            },
        request_timeout=300
    )

    return query_results


def read_precomputed_encoding(path):
    """
    Reads the precomputed encoding from given file, together with the 
    garbage cluster that was used for the given feature. The garbage
    cluster is the largest cluster in the encoding.
    """
    precomputed_encoding = dict()
    with open(path, 'r') as f:
        next(f)
        for line in f.readlines():
            line = line.strip()
            line = line.split(',')
            precomputed_encoding[int(line[0])] = int(line[1])
    
    return precomputed_encoding

def compute_garbage_cluster(encoding_values):
    """
    Computes the garbage cluster, which is the largest cluster in the encoding.
    """
    return Counter(encoding_values).most_common(1)[0][0]

def load_precomputed_encoding(folder):
    """
    Loads the precomputed encoding from files.
    """
    feature_encodings = dict()
    garbage_clusters = dict()
    for f in ['bytes', 'packets', 'duration']:
        feature_encodings[f] = read_precomputed_encoding(f'{folder}_{f}.csv')
        garbage_clusters[f] = compute_garbage_cluster(feature_encodings[f].values())
    return feature_encodings, garbage_clusters

def compute_flow_correction(current_row, next_row):
    """
    Computes the correction for the current row and the next row. 
    The correction is done by taking the absolute difference between
    the two rows.
    """
    result = current_row.copy()
    result[5] = abs(current_row[5] - next_row[5])
    result[6] = abs(current_row[6] - next_row[6])
    result[7] = abs(current_row[7] - next_row[7])
    return result
	
def timing_correction(data):
    """
    Corrects the timing of the data. This is done by taking the absolute
    difference between the two rows. This is needed for flows collected 
    from the Elastic stack; there might be intermediate flows
    """
    result = []
    for i in range(len(data)):
        current_row = data[i]
        if i + 1 < len(data) and current_row[0] == data[i + 1][0]:
            next_row = data[i + 1]
            corrected = compute_flow_correction(current_row, next_row)
            result.append(corrected)
        else:
            result.append(current_row)

    return result

def remove_zero_rows(data):
    """
    Removes rows with zero bytes and zero packets.
    """
    result = []
    for row in data:
        if row[5] == 0.0 or row[6] == 0.0:
            continue
        else:
            result.append(row)
    
    return result

def ts_to_epoch(ts_serie_data):
    """
    Converts a timestamp to UNIX time.
    """
    return ts_serie_data.apply(lambda x: datetime.timestamp(datetime.strptime(x, '%Y-%m-%dT%H:%M:%S.%fZ')))
    # return (pd.to_datetime(ts_serie_data) - pd.Timestamp('1990-01-01T00:00:00.000Z')) // pd.Timedelta('1s')

def json_has_all_fields(json_object):
    """
    Checks if the json object has all the fields needed to be processed by the pipeline. If one field
    is missing, then we consider to not pass the check.
    """
    if '_source' not in json_object:
        return False
    
    for field in ['flow', '@timestamp', 'source', 'destination', 'network', 'event']:
        if field not in json_object['_source']:
            return False
    
    for field in ['bytes', 'packets', 'transport']:
        if field not in json_object['_source']['network']:
            return False

    if 'ip' not in json_object['_source']['source'] and 'ip' not in json_object['_source']['destination']:
        return False

    if 'duration' not in json_object['_source']['event']:
        return False

    if 'id' not in json_object['_source']['flow']:
        return False
    
    if 'port' not in json_object['_source']['source'] or 'port' not in json_object['_source']['destination']:
        return False

    return True

def json_to_df(raw_json_data, ip_address):
    """
    Converts the data collected from Elastic Stack to the format needed for the pipeline
    """
    print('Converting Elastic Stack data to format needed for pipeline')
    data = []
    for line in raw_json_data:
        json_line_obj = json.loads(line)
        if json_has_all_fields(json_line_obj):
            # Only need data from the pod that we are monitoring
            if json_line_obj['_source']['source']['ip'] == ip_address or json_line_obj['_source']['destination']['ip'] == ip_address:
                data.append(
                    {
                        'flow_id': json_line_obj['_source']['flow']['id'],
                        'timestamp': json_line_obj['_source']['@timestamp'],
                        'src_ip': json_line_obj['_source']['source']['ip'],
                        'dst_ip': json_line_obj['_source']['destination']['ip'],
                        'protocol': json_line_obj['_source']['network']['transport'],
                        'bytes': json_line_obj['_source']['network']['bytes'],
                        'packets': json_line_obj['_source']['network']['packets'],
                        'duration': json_line_obj['_source']['event']['duration'],
                        'src_port': json_line_obj['_source']['source']['port'],
                        'dst_port': json_line_obj['_source']['destination']['port']
                    }
            )
        else:
            continue
    

    if len(data) < 1:
        print('No (new) data found for the given service IP address')
        return None


    df = pd.DataFrame(data).sort_values(by=['flow_id', 'timestamp'])
    df['timestamp'] = ts_to_epoch(df['timestamp'])
    df['duration'] = df['duration'] / 1000
    df = df.astype({'bytes': 'int64','packets': 'int64','duration': 'int64', 'src_port': 'int64', 'dst_port': 'int64'})
    df['dst_ip'] = df['dst_ip'].str.strip()
    df['src_ip'] = df['src_ip'].str.strip()
    df['dst_ip'] = df['dst_ip'].str.strip('\t')
    df['src_ip'] = df['src_ip'].str.strip('\t')
    columns = df.columns.tolist()
    timing_corrected_data = timing_correction(df.values.tolist())
    zero_rows_removed = remove_zero_rows(timing_corrected_data)
    return pd.DataFrame(zero_rows_removed, columns=columns)


def compute_encoding(feature_data, feature_encoding, garbage_cluster):
    """
    Compute the encoding for the given feature data.
    """
    encoded_feature_data = []
    for d in feature_data:
        if d in feature_encoding:
            encoded_feature_data.append(feature_encoding[d])
        else:
            encoded_feature_data.append(garbage_cluster)

    return encoded_feature_data

def encode_data(data, output_folder_path, precomputed=False):
    """
    Encodes collected NetFlows using ENCODE algorithm. This is done a pre-processing step.
    The dataframe is tranformed into the right format for learning a state machine model using
    FlexFringe.
    """
    print('Encoding data')
    if precomputed:
        feature_encodings, garbage_clusters = load_precomputed_encoding(output_folder_path.split('/')[-1])
    else:
        bytes_encoding = encode(
            'bytes',
            {'timestamp': 'timestamp', 'src_ip':'src_ip', 'dst_ip':'dst_ip'},
            False,
		    'ts',
		    10,
		    35,
		    output_folder_path,
            data=data
        )
        
        packets_encoding = encode(
            'packets',
            {'timestamp': 'timestamp', 'src_ip':'src_ip', 'dst_ip':'dst_ip'},
            False,
		    'ts',
		    10,
		    35,
		    output_folder_path,
            data=data
        )
        
        duration_encoding = encode(
            'duration',
            {'timestamp': 'timestamp', 'src_ip':'src_ip', 'dst_ip':'dst_ip'},
            True,
		    'ts',
		    10,
		    35,
		    output_folder_path,
            data=data
        )
        
        feature_encodings = {
            'bytes': bytes_encoding,
            'packets': packets_encoding,
            'duration': duration_encoding
        }

        garbage_clusters = {
            'bytes': compute_garbage_cluster(bytes_encoding),
            'packets': compute_garbage_cluster(packets_encoding),
            'duration': compute_garbage_cluster(duration_encoding)
        }

    
    data['symb:bytes_encoding'] = compute_encoding(data['bytes'].values.tolist(), feature_encodings['bytes'], garbage_clusters['bytes'])
    data['symb:packets_encoding'] = compute_encoding(data['packets'].values.tolist(), feature_encodings['packets'], garbage_clusters['packets'])
    data['symb:duration_encoding'] = compute_encoding(data['duration'].values.tolist(), feature_encodings['duration'], garbage_clusters['duration'])
    data.rename(columns={'protocol': 'symb:protocol'}, inplace=True)
    return data


def write_anomalies_to_file(anomalies, output_file_path):
    """
    Writes the anomalies detected by FlexFringe to a file.
    """
    print('Writing anomalies to file')
    with open(output_file_path, 'w') as f:
        for anomaly in anomalies:
            f.write(str(anomaly) + '\n')


def preprocess_training_data(training_data_path, precomputed_encoding=False):
    """
    Preprocess the training data of the given path. 
    Data must satisfy the following criteria: 
    (1) Must be in CSV format,
    (2) Must have the following features: flow_id, timestamp, src_ip, dst_ip, protocol, bytes, packets and duration.
    (3) The timestamp data must be in UNIX time format (seconds).
    (4) Must only be benign data.

    The training data is first encoded with the ENCODE algorithm and then it is written to a file. This makes it
    easier to calling the fit and predict functions of FlexFringe wrapper; the learnt model is always saved under
    same name and this makes is easier if we want to use the learnt model to do predictions. 
    """
    print('Loading training data')
    training_data = pd.read_csv(training_data_path)
    output_folder = '/'.join(training_data_path.split('/')[0:-1]) + '/'
    encoded_training_data = encode_data(training_data, output_folder, precomputed=precomputed_encoding)
    encoded_training_data_path = output_folder + 'encoded_training_data.csv'
    encoded_training_data.to_csv(encoded_training_data_path, sep=',', index=False)
    return encoded_training_data_path