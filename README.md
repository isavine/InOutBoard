## How to prepare the application for the first run:
1. Clone the application from GitHub:
```
$ cd path/to/work/directory
$ git clone https://github.com/tommyhuynh/InOutBoard.git
$ cd InOutBoard
```
2. Create virtual environment and install dependencies:
```
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```
3. Customize initial settings:
```
$ mkdir instance
$ cp example_settings.py instance/settings.py
$ nano instance/settings.py
```

## How to start the application:
```
$ cd path/to/InOutBoard
$ source venv/bin/activate
$ export INOUTBOARD_SETTINGS=instance/settings.py
$ python app.py
```
