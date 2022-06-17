
linux:
	go build
	GOOS=windows GOARCH=amd64 go build
clean:
	rm -f netx netx.exe
