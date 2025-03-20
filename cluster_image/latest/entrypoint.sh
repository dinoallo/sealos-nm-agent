#!/usr/bin/env bash
nodeCIDR="${NODE_CIDR:-192.168.0.0/24}"
podCIDR="${POD_CIDR:-100.64.0.0/16}"
hostDevs="${HOST_DEVS:-ens4,ens8}"
trafficDataBatchSize=10000
version=latest
namespace="sealos-nm-system"
deploy_name="sealos-nm-agent"
configmap_name="agent-env"
secret_name="nm-db-conn-credential"
mongodbUri=$MONGO_URI
mongodbVersion="mongodb-${MONGODB_VERSION:-6.0}"
databaseReplica=3
databaseName="sealos-networkmanager"
db_namespace="sealos"
db_name="nm-traffic-db"
db_secret_name="$db_name-conn-credential"

manifest_dir="manifests"
namespace_file="$manifest_dir/ns.yaml"
configmap_file="$manifest_dir/configmap.yaml"
secret_file="$manifest_dir/secret.yaml"
db_file="$manifest_dir/db.yaml"
deploy_file="$manifest_dir/deploy.yaml"

databaseMongodbURIPlaceholder="<mongodb-uri-placeholder>"
databaseMongodbVersionPlaceholder="<mongodb-version-placeholder>"
databaseNamePlaceholder="<db-name-placeholder>"
databaseReplicaPlaceholder="<replica-placeholder>"
namespacePlaceholder="<namespace-placeholder>"
namePlaceholder="<name-placeholder>"
secretPlaceholder="<secret-placeholder>"
configmapPlaceholder="<configmap-placeholder>"
versionPlaceholder="<version-placeholder>"
nodeCIDRPlaceholder="<node-cidr-placeholder>"
podCIDRPlaceholder="<pod-cidr-placeholder>"
hostDevsPlaceholder="<host-devices-placeholder>"
trafficDataBatchSizePlaceholder="<traffic-data-batch-size-placeholder>"




function prepare {
    update_ns
    gen_mongodbUri
    update_secret
    update_config
    update_deploy
}
function get_mongodbUri() {

secret_data=$(kubectl get secret -n $db_namespace $db_secret_name -o go-template='{{range $k,$v := .data}}{{printf "%s: " $k}}{{if not $v}}{{$v}}{{else}}{{$v | base64decode}}{{end}}{{"\n"}}{{end}}')
#endpoint=$(echo "$secret_data" | awk -F': ' '/endpoint/ {print $2}')
#headlessEndpoint=$(echo "$secret_data" | awk -F': ' '/headlessEndpoint/ {print $2}')
#headlessHost=$(echo "$secret_data" | awk -F': ' '/headlessHost/ {print $2}')
#headlessPort=$(echo "$secret_data" | awk -F': ' '/headlessPort/ {print $2}')
host=$(echo "$secret_data" | awk -F': ' '/host/ {print $2}')
password=$(echo "$secret_data" | awk -F': ' '/password/ {print $2}')
port=$(echo "$secret_data" | awk -F': ' '/port/ {print $2}')
username=$(echo "$secret_data" | awk -F': ' '/username/ {print $2}')

mongodb_uri="mongodb://$username:$password@$host.$db_namespace.svc:$port"

echo "$mongodb_uri"
}


function gen_mongodbUri() {
  # if mongodbUri is empty then create mongodb and gen mongodb uri
  if [ -z "$mongodbUri" ]; then
    echo "no mongodb uri found, create mongodb and gen mongodb uri"
    update_db
    retry_kubectl_apply $db_file
    echo "waiting for mongodb secret generated"
    message="waiting for mongodb ready"
    # if there is no sealos-mongodb-conn-credential secret then wait for mongodb ready
    while [ -z "$(kubectl get secret -n $db_namespace $db_secret_name 2>/dev/null)" ]; do
      echo -ne "\r$message   \e[K"
      sleep 0.5
      echo -ne "\r$message .  \e[K"
      sleep 0.5
      echo -ne "\r$message .. \e[K"
      sleep 0.5
      echo -ne "\r$message ...\e[K"
      sleep 0.5
    done
    echo "mongodb secret has been generated successfully."
    mongodbUri=$(get_mongodbUri)
  fi
}

function update_ns {
  echo "ensure a namespace $namespace"
  # update namespace
  sed -i "s|$namePlaceholder|$namespace|g" $namespace_file
  kubectl apply -f $namespace_file || { echo "Command failed. Exiting script."; exit 1; }
}

function update_db {
  echo "the db will be installed as $db_namespace/$db_name"
  # update name and namespace
  sed -i "s|$namespacePlaceholder|$db_namespace|g" $db_file
  sed -i "s|$namePlaceholder|$db_name|g" $db_file
  # use generated values to update configmap
  echo "update $db_name db"
  # update db version
  echo "version: $mongodbVersion"
  sed -i "s|$databaseMongodbVersionPlaceholder|$mongodbVersion|g" $db_file
  # update number of replica
  echo "replica: $databaseReplica"
  sed -i "s|$databaseReplicaPlaceholder|$databaseReplica|g" $db_file
}

function update_config {
  echo "the configmap will be installed as $namespace/$configmap_name"
  # update name and namespace
  sed -i "s|$namespacePlaceholder|$namespace|g" $configmap_file
  sed -i "s|$namePlaceholder|$configmap_name|g" $configmap_file
  # use generated values to update configmap
  echo "update $configmap_name configmap"
  # update node cidr
  echo "nodeCidr: $nodeCIDR"
  sed -i "s|$nodeCIDRPlaceholder|$nodeCIDR|g" $configmap_file
  # update pod cidr
  echo "podCidr: $podCIDR"
  sed -i "s|$podCIDRPlaceholder|$podCIDR|g" $configmap_file
  # update host devs
  echo "host devs: $hostDevs"
  sed -i "s|$hostDevsPlaceholder|$hostDevs|g" $configmap_file
  # update traffic data batch size
  echo "traffic data batch size: $trafficDataBatchSize"
  sed -i "s|$trafficDataBatchSizePlaceholder|$trafficDataBatchSize|g" $configmap_file
  echo "apply $configmap_name configmap"
  kubectl apply -f $configmap_file || { echo "Command failed. Exiting script."; exit 1; }
}

function update_secret {
  echo "the secret will be installed as $namespace/$secret_name"
  # update name and namespace
  sed -i "s|$namespacePlaceholder|$namespace|g" $secret_file
  sed -i "s|$namePlaceholder|$secret_name|g" $secret_file
  # use generated values to update secret
  echo "update $secret_name secret"
  # update mongodb uri
  echo "mongodbUri: $mongodbUri"
  sed -i "s|$databaseMongodbURIPlaceholder|$(echo -n "$mongodbUri" | base64 -w 0)|g" $secret_file
  # update db name
  echo "databaseName: $databaseName"
  sed -i "s|$databaseNamePlaceholder|$(echo -n "$databaseName" | base64 -w 0)|g" $secret_file
  # apply secret
  echo "apply $secret_name secret"
  kubectl apply -f $secret_file || { echo "Command failed. Exiting script."; exit 1; }
}

function update_deploy {
  echo "the app will be installed as $namespace/$deploy_name"
  # update name and namespace
  sed -i "s|$namespacePlaceholder|$namespace|g" $deploy_file
  sed -i "s|$namePlaceholder|$deploy_name|g" $deploy_file
  echo "update $deploy_name app"
  # update version
  echo "version: $version"
  sed -i "s|$versionPlaceholder|$version|g" $deploy_file
  # update secret
  echo "secret: $secret_name"
  sed -i "s|$secretPlaceholder|$secret_name|g" $deploy_file
  # update configmap
  echo "configmap: $configmap_name"
  sed -i "s|$configmapPlaceholder|$configmap_name|g" $deploy_file

}

function deploy {
  # apply app
  echo "apply $deploy_name app"
  kubectl apply -f $deploy_file || { echo "Command failed. Exiting script."; exit 1; }
}


retry_kubectl_apply() {
    local file_path=$1  # The path to the Kubernetes manifest file
    local max_attempts=6  # Maximum number of attempts
    local attempt=0  # Current attempt counter
    local wait_seconds=10  # Seconds to wait before retrying

    while [ $attempt -lt $max_attempts ]; do
        # Attempt to execute the kubectl command
        kubectl apply -f "$file_path" >> /dev/null && {
            return 0  # Exit the function successfully
        }
        # If the command did not execute successfully, increase the attempt counter and report failure
        attempt=$((attempt + 1))
        # If the maximum number of attempts has been reached, stop retrying
        if [ $attempt -eq $max_attempts ]; then
            return 1  # Exit the function with failure
        fi
        # Wait for a specified time before retrying
        sleep $wait_seconds
    done
}

function install {
  prepare
  deploy
}

install