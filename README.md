# imageproc

A4 of UQ's famous CSSE2310. 

imageproc allows multiple concurrently connected clients to send image editing requests and responds with the edited image in real time. The client is also included in this repository. Communication between clients and the server is over TCP using HTTP.

The server includes connection limiting features as well as statistics reporting (currently connected clients, num completed clients, successfully fulfilled HTTP requests, unsuccessful HTTP requests, and total operations).

Unless you have access to the internal library used during the semester (for some reason), it is unlikely you'll be able to get this to run. However, I thought this was worth uploading as it may serve as a decent reference point for someone who is developing a similar application. I'm also somewhat proud of my work here (though I did do a minor refactor before uploading this).
