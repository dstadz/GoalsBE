import { Application } from 'http://deno.land/x/oak/mod.ts'
import { oakCors } from "https://deno.land/x/cors/mod.ts";


import usersRouter from './routes/users.ts'
import goalsRouter from './routes/goals.ts'
import habitsRouter from './routes/habits.ts'


const port = 8000

const app = new Application()

app.use(oakCors())

// app.use(({req, res, next}:
//   {req:any, res:any, next:any}) => {
//   res.header('Access-Control-Allow-Origin', '*');
//   next();
// });

app.use(usersRouter.routes())
app.use(goalsRouter.routes())
app.use(habitsRouter.routes())

app.use(usersRouter.allowedMethods())
app.use(goalsRouter.allowedMethods())
app.use(habitsRouter.allowedMethods())


console.log(`\n\n server live on port ${port} \n\n`)

await app.listen({ port })