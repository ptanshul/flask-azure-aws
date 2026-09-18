from fastapi import FastAPI

app = FastAPI()

@app.get("/add")
def add():
    return {"result": 10 + 20}