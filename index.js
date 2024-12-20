const { default: axios } = require('axios');
const express = require('express');
const cors = require('cors')
const crypto = require('crypto')
const jwt = require('jsonwebtoken');
const morgan = require('morgan');

require('dotenv').config();

const app = express();
app.use(express.json())
app.use(cors('*'))
app.use(morgan('dev'))

app.get('/api/slack/connect', (req, res) => {
  const randomBytes = crypto.randomBytes(16).toString('hex');

  try {
    const userScopes = 'search:read,channels:read,groups:read,im:read,mpim:read,search:read';
    const slackAuthUrl = `https://slack.com/oauth/v2/authorize?client_id=${process.env.SLACK_CLIENT_ID}` +
      `&user_scope=${userScopes}` +
      `&redirect_uri=${encodeURIComponent(process.env.SLACK_REDIRECT_URI.trim())}` +
      `&state=${randomBytes}`;

    res.json({ authUrl: slackAuthUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.get('/api/slack/oauth/verify', async (req, res) => {
  const { code, state } = req.query;

  try {
    const response = await fetch('https://slack.com/api/oauth.v2.access', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        client_id: process.env.SLACK_CLIENT_ID,
        client_secret: process.env.SLACK_CLIENT_SECRET,
        code: code,
        redirect_uri: process.env.SLACK_REDIRECT_URI
      })
    });

    const data = await response.json();


    if (!data.ok) {
      throw new Error(`Slack OAuth error: ${data.error}`);
    }

    const randomBytes = crypto.randomBytes(16).toString('hex');

    const signedToken = jwt.sign({
      accessToken: data.authed_user.access_token,
      teamId: data.team.id,
      teamName: data.team.name,
      userId: data.authed_user.id
    }, process.env.JWT_SIGNING_SECRET, {
      algorithm: 'HS256', header: {
        id: randomBytes, // Add a random UUID to the header
      },
    })

    res.status(200).json({
      signedToken,
      success: true
    })

  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    })
  }
});

app.get('/api/fetch-channels', async (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];
  if (!token) throw new Error('Invalid authorization')
  const decoded = jwt.verify(token, process.env.JWT_SIGNING_SECRET);
  const accessToken = decoded.accessToken;

  try {
    const response = await axios.get('https://slack.com/api/conversations.list', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
      params: {
        types: 'public_channel,private_channel',
      },
    });

    if (response.data.ok) {
      res.json(response.data.channels);
    } else {
      res.status(500).json({ error: response.data.error });
    }
  } catch (error) {
    console.error('Error fetching channels:', error);
    res.status(500).json({ error: 'Failed to fetch channels' });
  }
});

app.post('/api/search-message', async (req, res) => {
  const { channelId, query } = req.body;
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Invalid authorization' });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SIGNING_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  const accessToken = decoded.accessToken;

  try {
    if (!channelId || !accessToken || !query) {
      throw new Error('All fields must be provided');
    }

    const allMessages = [];

    for (const q of query) {
      const data = await axios.post(
        'https://slack.com/api/search.messages',
        new URLSearchParams({
          query: `${q} in:${channelId}`,
          highlights: 'true'
        }),
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/x-www-form-urlencoded'
          },
        }
      );

      // Add the messages from each query to the allMessages array
      if (data.data.messages) {
        allMessages.push(...data.data.messages.matches);
      }
    }

    const uniqueMessages = Array.from(
      new Map(allMessages.map(msg => [msg.ts, msg])).values()
    );

    const filteredMessages = uniqueMessages.map((x) => {
      return {
        text: x.text,
        ts: x.ts,
      };
    })

    const sortedMessages = filteredMessages.sort((a, b) => parseFloat(a.ts) - parseFloat(b.ts));

    res.status(200).json({
      messages: sortedMessages
    });
  } catch (err) {
    console.error('Error searching messages:', err);
    res.status(500).json({ error: 'Failed to search messages' });
  }
});



app.listen(8080, () => {
  console.log('Server is running on port 8080')
})