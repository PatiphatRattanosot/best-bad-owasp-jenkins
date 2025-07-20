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
      }
    }
  }
}
