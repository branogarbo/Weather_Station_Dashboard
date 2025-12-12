## How to run this project:

### With locally installed Python:
1. Clone this repository and `cd` into it.
2. Create your virtual environment with `python3 -m venv .venv`
3. Activate your virtual environment with `source .venv/bin/activate` if you're on a UNIX-like system.
4. Install the required packages with `pip install -r requirements.txt`
5. Start a flask development server with `python3 app.py`

### With docker (assuming you have it installed):
1. Clone this repository and `cd` into it.
2. Run `docker compose up -d`