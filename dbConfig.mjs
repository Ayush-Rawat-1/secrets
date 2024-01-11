import dotenv from "dotenv";
dotenv.config();
import pg from "pg";

const db=new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
    password: process.env.DB_PASSWORD
});
db.connect();
export { db };