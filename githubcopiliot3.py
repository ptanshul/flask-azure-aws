#Create a Kubernetes Deployment for a FastAPI application.
import fastapi


apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-deployment
spec:
  replicas: 3
    selector:
        matchLabels:
            app: fastapi
    template:
        metadata:
            labels:
                app: fastapi    
        spec:
            containers:
            - name: fastapi-container
                image: your-docker-image:latest
                ports:
                - containerPort: 80
