# Use the official Python 3.9 slim image as the base
FROM python:3.9-slim

# Install system dependencies for Tkinter and Xvfb
RUN apt-get update && \
    apt-get install -y \
    python3-tk \
    xvfb \
    x11vnc \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed Python packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Set the DISPLAY environment variable
ENV DISPLAY=:99

# Start Xvfb, VNC server, and your application
CMD ["sh", "-c", "Xvfb :99 -screen 0 1024x768x24 & x11vnc -rfbauth ./pass -display :99 -N -forever & python arpsentry.py"]
