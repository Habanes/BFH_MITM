# Use a lightweight Python image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy all python scripts
COPY *.py ./

# Install the cryptography library
RUN pip install cryptography

# Command to run the script
CMD ["python", "main.py"]
