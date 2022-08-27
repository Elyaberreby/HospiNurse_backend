const indexR = require("./index");
const usersR = require("./users");

exports.routesInit = (app) => {
  app.use("/",indexR);
  app.use("/users", usersR);


  app.use((req,res) => {
    res.status(404).json({msg_error:"Url not found, 404!"});
  })
}
