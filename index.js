const { createProbot } = require('probot')
const { resolve } = require('probot/lib/resolver')
const { findPrivateKey } = require('probot/lib/private-key')
const { template } = require('./views/probot')
const verify = require('@octokit/webhooks/verify')
const kms = require('@google-cloud/kms')

let probot

const getOpts = () => ({
  id: process.env.APP_ID,
  secret: process.env.WEBHOOK_SECRET,
  cert: findPrivateKey()
})

const getOptsKms = async () => {
  const {
    APP_ID: id,
    WEBHOOK_SECRET: encWebhookSecret,
    PRIVATE_KEY: encPrivateKey,
    KMS_KEY_ID: keyPath
  } = process.env
  const kmsClient = new kms.KeyManagementServiceClient()
  const [secret, cert] = await Promise.all([encWebhookSecret, encPrivateKey].map(
    ciphertext => kmsClient.decrypt({
      name: keyPath,
      ciphertext
    }).then(data => data[0].plaintext.toString())
  ))
  return {id, secret, cert}
}

const loadProbot = (opts, appFn) => {
  probot = probot || createProbot(opts)

  if (typeof appFn === 'string') {
    appFn = resolve(appFn)
  }

  probot.load(appFn)

  return probot
}

const makeServerless = getOpts => appFn => {
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
    const opts = await getOpts()
    probot = probot || loadProbot(opts, appFn)

    // Determine incoming webhook event type
    const name = request.get('x-github-event') || request.get('X-GitHub-Event')
    const id = request.get('x-github-delivery') || request.get('X-GitHub-Delivery')
    const signature = request.get('x-hub-signature') || request.get('X-Hub-Signature')

    const body = request.body
    const matchesSignature = verify(probot.options.secret, body, signature)
    if (!matchesSignature) {
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

module.exports.serverless = makeServerless(getOpts)
module.exports.serverlessKms = makeServerless(getOptsKms)
