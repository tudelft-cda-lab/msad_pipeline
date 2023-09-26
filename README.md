# Runtime Anomaly Detection Pipeline using State Machines for Microservice Architectures
This repository contains the source code for the runtime anomaly detection pipeline developed for the AssureMOSS project (Work Package 4). 

## Installation
The pipeline is implemented in Python 3 and uses the following libraries:
- pandas>=1.3.5
- numpy>=1.20.0
- tqdm>=4.62.3
- elasticsearch==7.12.1
- encode-netflow==0.3.0

You can install the required libraries using the following command:
```
pip install -r requirements.txt
```

You will also have to install python-wrapper for the Flexfringe tool by cloning the following repository:
```
git clone https://github.com/ClintonCao/FlexFringe-python.git
```
and then installing the package using the following command:
```
pip install .
```

## Usage
You can use the `ms_detection.py` script to do detection on a network level and the `runtime_monitoring.py` script to do detection on a pod level.

