import { Application } from 'http://deno.land/x/oak/mod.ts'
import userRouter from './routes/users.ts'
const port = 8000

const app = new Application()

app.use(userRouter.routes())
app.use(userRouter.allowedMethods())

console.log(`server live on port  ${port}`)

await app.listen({ port })