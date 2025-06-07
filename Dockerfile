# Use official Python runtime as a parent image
FROM python:3.8-slim

# Set working directory
WORKDIR /app

# Copy current directory contents into the container
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose port for FastAPI if needed
EXPOSE 8000

# Default command to run when starting the container
CMD ["uvicorn", "threat_analysis_agent:app", "--host", "0.0.0.0", "--port", "8000"]
