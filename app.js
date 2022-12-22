const express = require("express");
const path = require("path");
const http = require("http");
const cors = require('cors')
const { routesInit, corsAccessControl } = require("./routes/config_routes");
require("./db/mongoConnect");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

routesInit(app);


const server = http.createServer(app);
let port = process.env.PORT || "3004";
server.listen(port);