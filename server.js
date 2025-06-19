const express = require('express'); // // Include the express module

const app = express(); // Instantiate express app.

app.use(express.json()); //Middleware to conver json to javascript object.

const PORT = 5001;
app.listen(5001, (error) => {
    if(error) {
        console.log("Error starting the server", error);
    } else {
        console.log(`server is running at: http://localhost:${PORT}`);
    }
});
