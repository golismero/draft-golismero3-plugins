.PHONY: all

debug: image
	@docker run -it --entrypoint /bin/sh golismero-python3-formatters

image:
	@docker build . -t golismero-python3-formatters

prune:
	@docker rmi -f golismero-python3-formatters
	@docker system prune -f