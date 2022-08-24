const mongoose = require('mongoose');
const { config } = require('../config/secret')

main().catch(err => console.log(err));

async function main() {
    await mongoose.connect(`mongodb://localhost:27017/hospiNurse_backend`);
    console.log("mongo conect")
}
