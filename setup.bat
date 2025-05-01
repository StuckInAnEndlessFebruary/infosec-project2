@echo off
echo 🔧 Setting up Python virtual environment...
python -m venv venv

echo 🔁 Activating virtual environment...
call venv\Scripts\activate

echo 📦 Installing dependencies...
pip install --upgrade pip
pip install -r requirements.txt

IF NOT EXIST .env (
    echo 📝 Creating default .env file...
    echo SECRET_KEY=your-secret-key>> .env
    echo JWT_SECRET_KEY=your-jwt-secret-key>> .env
    echo PEPPER=your-pepper-string>> .env
    echo MASTER_KEY=your-master-password>> .env
    echo DATABASE_URL=sqlite:///secure_api.db>> .env
) ELSE (
    echo ✅ .env file already exists.
)

echo 🛠 Initializing database...
set FLASK_APP=app.py
python -c "from models import db; from app import app; with app.app_context(): db.create_all()"

echo 🚀 Setup complete. You can now run the app with:
echo venv\Scripts\activate
echo flask run
pause
