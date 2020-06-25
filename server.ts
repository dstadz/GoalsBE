import { Application } from 'http://deno.land/x/oak/mod.ts'
import { oakCors } from "https://deno.land/x/cors/mod.ts";


import userRouter from './routes/users.ts'
import goalRouter from './routes/goals.ts'
const port = 8000

const app = new Application()

app.use(oakCors())

app.use(userRouter.routes())
app.use(userRouter.allowedMethods())
app.use(goalRouter.routes())
app.use(goalRouter.allowedMethods())

console.log(`\n\n server live on port  ${port} \n\n`)

await app.listen({ port })