import { Application } from "https://deno.land/x/oak/mod.ts";
import { oakCors } from "https://deno.land/x/cors/mod.ts";


import userRouter from './routes/users.ts'
import goalsRouter from './routes/goals.ts'
import habitsRouter from './routes/habits.ts'

const port = 8000
const app = new Application()

app.use(
  oakCors({
    origin: "http://localhost:3000"
  }),
);
// app.use(oakCors())


app.use(goalsRouter.routes())
app.use(habitsRouter.routes())
app.use(userRouter.routes())

app.use(goalsRouter.allowedMethods())
app.use(habitsRouter.allowedMethods())
app.use(userRouter.allowedMethods())


console.log(`\n\n server live on port ${port} \n\n`)

await app.listen({ port })