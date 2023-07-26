@Library('gematik-jenkins-shared-library') _

pipeline {
  options {
      disableConcurrentBuilds()
      buildDiscarder logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '', daysToKeepStr: '', numToKeepStr: '5')
  }

  agent { label 'k8-maven-small' }

  stages {

    stage('Check certificate validity') {
      steps {
        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
          sh """
            bash testDataTemplates/checkCertValidity.sh testDataTemplates/certificates/
          """
        }
      }
    }

    stage('Check TSL validity') {
      steps {
        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
          sh """
            bash testDataTemplates/checkTslValidity.sh testDataTemplates/tsl/
          """
        }
      }
    }

  }

  post {
    changed {
      sendEMailNotification(getPkiTsEMailList(), false)
      cleanWs()
    }
    failure {
      sendEMailNotification(gitGetCommitterEMailAddress(), false)
      cleanWs()
    }
  }

}
