FROM python:3.11-slim

WORKDIR /app

# System dependencies (ffmpeg download karne ke liye)
RUN apt-get update && apt-get install -y ffmpeg

COPY requirements.txt .

# FIX: PyPI ke official channels se official master version install hoga (No 404 Error)
RUN pip install --no-cache-dir -U yt-dlp

# Aapki baki saari requirements (FastAPI, Uvicorn, etc.) yahan install hongi
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

CMD ["python", "main.py"]