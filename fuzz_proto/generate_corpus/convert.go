package main

import (
	"bufio"
	"os"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/golang/protobuf/proto"

	"./uwsgifuzz"
)

func main() {
	srcDir := os.Args[1]
	dstDir := os.Args[2]
	files, err := ioutil.ReadDir(srcDir)

	if err != nil {
		panic(err)
	}

	for _, fileInfo := range files {
		if fileInfo.IsDir() {
			continue
		}
		name := fileInfo.Name()
		println(name)
		srcFile, err := os.Open(path.Join(srcDir, name))
		if err != nil {
			panic(err)
		}
		req, err := http.ReadRequest(bufio.NewReader(srcFile))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			srcFile.Close()
			continue
		}
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			srcFile.Close()
			continue
		}
		dstFile, err := os.Create(path.Join(dstDir, name))
		if err != nil {
			panic(err)
		}
		rp := &uwsgifuzz.HttpRequest{
			Method: []byte(req.Method),
			Uri: []byte(req.URL.RequestURI()),
			Version: []byte(req.Proto),
			Headers: make([]*uwsgifuzz.Header, 0, len(req.Header)),
			Body: body,
		}
		
		for k, v := range req.Header {
			for _, hVal := range v {
				rp.Headers = append(rp.Headers, &uwsgifuzz.Header{
					Key: []byte(k), Value: []byte(hVal),
				})
			}
		}
		err = proto.MarshalText(dstFile, rp)
		if err != nil {
			panic(err)
		}
		dstFile.Close()
	}

}