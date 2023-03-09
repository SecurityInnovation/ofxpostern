FROM python

WORKDIR /usr/src/app
COPY requirements.txt .
RUN  pip install -r requirements.txt
COPY . .

ENTRYPOINT ["python", "ofxpostern.py"]
