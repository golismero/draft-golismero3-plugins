.PHONY: all

PLUGIN=`basename $(realpath .)`
VERSION=`cat VERSION`

test: image
	@cat example-input.json | docker run -i golismero-plugin-${PLUGIN} > test-output.json
	@python -c "import json; exit(int(json.load(open('example-output.json', 'rU')) != json.load(open('test-output.json', 'rU'))))"

debug: image
	@docker run -it --entrypoint /bin/sh golismero-plugin-${PLUGIN}

image:
	@docker build . -t golismero-plugin-${PLUGIN}
	@docker build . -t golismero-plugin-${PLUGIN}:${VERSION}

prune:
	@docker rmi -f golismero-plugin-${PLUGIN}
	@docker system prune -f