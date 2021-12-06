# Common Threat Vectors 
## Demo for CMSC 121: Web Programming

## SQL Injection & XSS Attack Demo

### Dependencies
Run the following command in cmd:

```
$pip install -r requirements.txt
```

### Usage
1. To use, create a .env file containing the key-value pair:
```
SECRET_KEY="<your_secret_key>"
```

2. Initialize the database by running the following code in Python Shell:
```
$python
>>> from app import init
>>> init()
>>> exit()
```

3. To run the web application, run the following command:
```
$python app.py
```

### Usage (Using CS50 IDE)
1. To use, create a .env file containing the key-value pair:
```
SECRET_KEY="<your_secret_key>"
```

2. Initialize the database by running the following code in Python Shell:
```
$python
>>> from app import init
>>> init()
>>> exit()
```

3. To run the web application, run the following command:
```
flask run
```


## Performing SQL Injection Attack
SQL Injection Attack is demonstrated in this application.

## Performing XSS Attack
Reflected and Stored XSS Attack is demonstrated in this application. 