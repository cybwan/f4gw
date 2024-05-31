//
// The proxy
//

var $target

pipy.listen(8000, $=>$
  .dump('>>>')
  .replaceData(
    function (data, i) {
      if (i === 0) {
        var h = data.shift(6).toArray()
        $target = `${h[0]}.${h[1]}.${h[2]}.${h[3]}:${(h[4]<<8)|h[5]}`
        println('Target:', $target)
      }
      return data
    }
  )
  .connect(() => $target)
  .dump('<<<')
)

//
// Mock target
//

pipy.listen(8080, $=>$.serveHTTP(new Message('hi')))

//
// Mock client
//

var client = pipeline($=>$
  .onStart(new Array(10).fill(new Message))
  .encodeHTTPRequest()
  .replaceData(
    function (data, i) {
      if (i === 0) {
        data = new Data([
          127, 0, 0, 1,
          8080 >> 8,
          8080 & 255,
        ]).push(data)
      }
      return data
    }
  )
  .connect('localhost:8000')
  .decodeHTTPResponse()
  .handleMessage(msg => println(msg.head))
)

client.spawn()
