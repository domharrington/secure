test:
	@./node_modules/.bin/mocha \
		-r should \
		-R spec

.PHONY: test