const { createProbot } = require('probot')
const { resolve } = require('probot/lib/resolver')
const { findPrivateKey } = require('probot/lib/private-key')
const { template } = require('./views/probot')
const verify = require('@octokit/webhooks/verify')

let probot

const loadProbot = appFn => {
  probot = probot || createProbot({
    id: process.env.APP_ID,
    secret: process.env.WEBHOOK_SECRET,
    cert: findPrivateKey()
  })

  if (typeof appFn === 'string') {
    appFn = resolve(appFn)
  }

  probot.load(appFn)

  return probot
}

module.exports.serverless = appFn => {
  return async (request, response) => {
    // 🤖 A friendly homepage if there isn't a payload
    if (request.method === 'GET' && request.path === '/probot') {
      return response.send({
        statusCode: 200,
        headers: { 'Content-Type': 'text/html' },
        body: template
      })
    }

    // Otherwise let's listen handle the payload
    probot = probot || loadProbot(appFn)

    // Determine incoming webhook event type
    const name = request.get('x-github-event') || request.get('X-GitHub-Event')
    const id = request.get('x-github-delivery') || request.get('X-GitHub-Delivery')
    const signature = request.get('x-hub-signature') || request.get('X-Hub-Signature')

    const body = request.body
    console.log(probot.options.secret)
    console.log(JSON.stringify(body, null, 2))
    console.log(signature)
    const matchesSignature = verify(probot.options.secret, body, signature)
    if (!matchesSignature) {
      console.log(probot.options.secret)
      console.log(JSON.stringify(body, null, 2))
      console.log(signature)
      console.error('signature does not match event payload and secret')
      response.sendStatus(400)
      return
    }
    // Do the thing
    console.log(`Received event ${name}${request.body.action ? ('.' + request.body.action) : ''}`)
    if (name) {
      try {
        await probot.receive({
          name,
          id,
          payload: body
        })
        response.send({
          statusCode: 200,
          body: JSON.stringify({ message: 'Executed' })
        })
      } catch (err) {
        console.error(err)
        response.send({
          statusCode: 500,
          body: JSON.stringify({ message: err })
        })
      }
    } else {
      console.error(request)
      response.sendStatus(400)
    }
  }
}
