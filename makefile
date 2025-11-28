IMG_NAME=sfr-rag-api-2
IMG_VERSION_TAG=0.0.1
IMG_NAME_PLUS_TAG=$(IMG_NAME):$(IMG_VERSION_TAG)
CONTAINER_NAME=sfr-rag-2

build: ./Dockerfile
	docker buildx build -t $(IMG_NAME_PLUS_TAG) .

clean-container: 
	docker rm -f $(CONTAINER_NAME)
	docker ps -a

clean-image: 
	docker rmi $(IMG_NAME_PLUS_TAG)
	docker images
	echo 'Image Cleaned!'

clean: clean-container clean-image

clean-build: clean build
	docker images

logs: 
	docker logs -f ${CONTAINER_NAME}

refresh: clean-build
	docker compose -f ./compose-rag.yaml up -d
	make logs

