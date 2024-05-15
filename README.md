aws ecr get-login-password --region ap-south-1 | docker login --username AWS --password-stdin 816586121361.dkr.ecr.ap-south-1.amazonaws.com

## Running

#BASE Image
docker build . -f Dockerfile-entity-auth-base -t entity-auth:base-1.7
docker tag dl-entity-auth:base-1.7 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:base-1.7
docker push 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:base-1.7

#LOCAL Image
docker build . -f Dockerfile-entity-auth-local -t entity-auth:local
docker run -dit -p 5002:5000 --restart=always -v D:\DIC\entity_auth\src_code:/opt/entity-auth-py --name entity-auth entity-auth:local
docker network connect diginet dl-entity-auth
docker network connect diginet dl-entity-auth
docker network connect diginet dl-entity-auth

#BETA/STAGE Image
docker build . -f Dockerfile-entity-auth-beta -t dl-entity-auth:beta
docker tag dl-entity-auth:beta 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:beta
docker push 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:beta

#PROD Image
docker build . -f Dockerfile-entity-auth-prod -t dl-entity-auth:prod
docker tag dl-entity-auth:prod 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:prod
docker push 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:prod