# noginx

A real-time NGINX anomaly detection and alert system.

**Demo video**
[demo_vid](https://github.com/user-attachments/assets/12cd769f-bc5b-4431-8f81-14718dbf2cec)

# Steps to Run noginx
- Make sure you have NGINX installed ( Did i really have to mention that?)
- It will automatically capture logs from "/var/log/nginx/access.log", this is where Unix stores its NGINX logs.
- Make a .env file, store it at root, it will include these fields:-
 ```json
    PREDICT_ONE_URL = "http://127.0.0.1:8000/predict_one"
    NOGINX_MAIL_ID = "****@gmail.com"
    NOGINX_MAIL_PASSWORD = "*** *** *** ***"
    RECEIVER_MAIL_ID = "***@gmail.com"
 ```
- Make sure you are in the root directory
- Start the server
- ```console
    cd fastapi_backend
    uvicorn api_server:app --reload
  ```
- On another terminal, Start the watcher
- ```console
    cd watcher
    python3 watcher.py
  ```


# ML Model
- Model is trained on the NGINX logs dataset publicly available at [nginx logs](https://github.com/elastic/examples/blob/master/Common%20Data%20Formats/nginx_logs/README.md)
- Model is trained using Isolation Forest algorithm.
- Model is saved at location noginx/data/model.pkl

# Features extraction and pre-processing
- Raw logs is processed using parse_logs.py and CSV file is stored at location noginx/data/nginx_logs.csv
- Features are extracted from the csv file using process_csv.py
- Mapping of raw features(string) to integer is done and stored in encoder_mappings.json at noginx/data/encoder_mappings.json

# Backend server
- FastAPI is used, and the server can be run via the file api_server.py at noginx/fastapi_backend/api_server.py
- Gives two endpoints
- 1.
     ```console
         /predict
     ```
     This returns the result if anomaly true or not for multiple logs at once.

     Request JSON format:
     ```json
        {
            "features": [{
                "status": 304,
                "size": 0,
                "method": 1,
                "path": 0,
                "user_agent": 54,
                "hour_of_day": 8
                }]
        }
     ```
- 2.
     ```console
         /predict_one
     ```
     This returns the result if anomaly true or not for just one log.

     Request JSON format:
     ```json
        {
            "feature": {
                "status": 304,
                "size": 0,
                "method": 1,
                "path": 0,
                "user_agent": 54,
                "hour_of_day": 8
                }
        }
     ```
    
- Response format
```json
        [
            {
                "anomaly": false
            }
        ]
```

## On detecting anomaly
 - It alerts the system by sending it a notification
 - Also send a mail to the user containing all the necessary info of the anomaly.

## Note:-
- For company specific usecases, you will need to train the model on the company specific data.
- For that either contact me at [Abhinav Jha](www.x.com/AbhinavXJ) else if you think you know the stuff then here are the steps
- Store all your NGINX logs at nginx.log at noginx/data/nginx.log
- RUN ```console
        python3 parse_logs.py
        ```
- RUN ```console
        python3 process_csv.py
      ```
- To train the model,
- RUN ```console
        python3 train_model.py
      ```
- You can customise the model via the feature engineering or tweaking with the Isolation Forest.