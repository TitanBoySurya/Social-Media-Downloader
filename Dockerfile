FROM python:3.11-slim

WORKDIR /app

# System dependencies (ffmpeg download karne ke liye)
RUN apt-get update && apt-get install -y ffmpeg

COPY requirements.txt .

# FIX: requirements se pehle yt-dlp ka latest nightly build forcefully install hoga
RUN pip install --no-cache-dir -U https://github.com/yt-dlp/yt-dlp-nightly-builds/releases/latest/download/yt_dlp-nightly.tar.gz

# Aapki baki saari requirements (FastAPI, Uvicorn, etc.) yahan install hongi
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

CMD ["python", "main.py"]