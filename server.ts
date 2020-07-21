import { Application } from "https://deno.land/x/oak/mod.ts";
import { oakCors } from "https://deno.land/x/cors/mod.ts";
import { parse } from "https://deno.land/std/flags/mod.ts";

import userRouter from './routes/users.ts'
import goalsRouter from './routes/goals.ts'
import habitsRouter from './routes/habits.ts'


const { args } = Deno;
const DEFAULT_PORT = 8080;
const argPort = parse(args).port;
const port = argPort ? Number(argPort) : DEFAULT_PORT;


const app = new Application()
app.use( oakCors({ origin: "http://localhost:3000" }) );
// app.use(oakCors())

app.use(goalsRouter.routes())
app.use(habitsRouter.routes())
app.use(userRouter.routes())

app.use(goalsRouter.allowedMethods())
app.use(habitsRouter.allowedMethods())
app.use(userRouter.allowedMethods())


console.log(`\n\n server live on port ${port} \n\n`)

await app.listen({ port })