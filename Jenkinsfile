pipeline {
  agent any
  environment {
    APP_NAME = 'test app name'
  }
  stages {
    stage("ZAP Testing") {
      steps {
        sh "echo ${APP_NAME}"
        sh "docker version"
        sh "docker run -t zaproxy/zap-stable zap-full-scan.py -t http://host.docker.internal:3000"
      }
    }
  }
}
