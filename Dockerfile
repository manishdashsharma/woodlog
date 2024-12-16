FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libgl1-mesa-glx \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgl1-mesa-dev \
    libgtk2.0-dev \
    libavcodec-dev \
    libavformat-dev \
    libswscale-dev \
    libv4l-dev \
    libatlas-base-dev \
    gfortran \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install OpenCV
RUN pip install opencv-python

# Copy the requirements file into the container
COPY ./requirements.txt /usr/src/app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the Django app code to the container
COPY . /usr/src/app

# Run migrations
RUN python manage.py makemigrations && python manage.py migrate

# Expose the port on which the Django app will run
EXPOSE 8000

# Command to run the Django app using Django's built-in server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]