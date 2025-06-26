# Use official Python runtime as a parent image
FROM python:3.8-slim

# Set working directory
WORKDIR /app

# Copy current directory contents into the container
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install flask

# Expose port for Flask app
EXPOSE 5000

# Default command to run when starting the container
CMD ["python", "api_server.py"]
