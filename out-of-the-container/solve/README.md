# Solution

First, we check out the dockerhub page for image and see the layers. We can inspect this using:
```
docker inspect windex123/config-tester:v1 -f '{{.RootFS.Layers}}'
docker save windex123/config-tester:v1 -o out.tar
```
We can then extract the file and inspect the suspicious second layer. We find a GCP service account key, which we can use in the following:
```
gcloud auth activate-service-account docker-builder@uoftctf-2025-docker-chal.iam.gserviceaccount.com --key-file=…/config.json
```
Now, we can perform some basic reconnaissance:
```
gcloud projects list
gcloud projects get-iam-policy uoftctf-2025-docker-chal
```
Through some digging, we find the following:
```
gcloud builds list
gcloud builds log 4a4bbc46-5a8b-4d36-a23f-39366ab2eac7
```
Looking at the log, we can find a GitHub link that reveals the flag.