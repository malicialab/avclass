FROM python:2
RUN mkdir /myapp
WORKDIR /myapp
ADD . /myapp
ENTRYPOINT ["python","/myapp/avclass_labeler.py"]
