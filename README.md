# ENTITY AUTH

## BASE Image

```bash
docker build . -f Dockerfile-entity-auth-base -t entity-auth:base-v1.0
docker tag entity-auth:base-v1.0 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:base-v1.0
```

## BETA Image

```bash
docker build . -f Dockerfile-entity-auth-beta -t entity-auth:beta
docker tag entity-auth:beta 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:beta
```

## STAGE Image

```bash
docker build . -f Dockerfile-entity-auth-stage -t entity-auth:stage
docker tag entity-auth:stage 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:stage
```

## PROD Image

```bash
docker build . -f Dockerfile-entity-auth-prod -t entity-auth:prod
docker tag entity-auth:prod 816586121361.dkr.ecr.ap-south-1.amazonaws.com/entity-auth:prod
```

## LOCAL Image

```bash
docker build . -f Dockerfile-entity-auth-local -t entity-auth:local
docker run -dit -p 5025:5000 -v D:\Work\DIC\Projects\Git\entity_auth\src_code:/opt/entity_auth-py --name entity-auth entity-auth:local
```

* Connect to network:

```bash
docker network connect diginetwork dl-entity-auth
```
