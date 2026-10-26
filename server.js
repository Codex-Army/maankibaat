// Race Condition CTF — intentionally vulnerable
app.post('/api/laptop/claim', async (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    const current = laptopClaims.get(sessionId) || 0;

    if (current >= 1) {
        return res.status(409).json({
            success: false,
            claimed: current,
            message: 'Laptop already claimed!'
        });
    }

    // Race window: concurrent requests can pass the check together.
    await new Promise(resolve => setTimeout(resolve, 200));

    // Intentionally use the previously-read value.
    // Concurrent requests can overwrite one another.
    const claimed = current + 1;
    laptopClaims.set(sessionId, claimed);

    return res.json({
        success: true,
        claimed,
        message: 'Laptop claim successful!',
        ...(claimed >= 20 ? { flag: RACE_FLAG } : {})
    });
});
