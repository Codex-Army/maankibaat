app.post('/api/laptop/claim', async (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    // Read current state.
    const current = laptopClaims.get(sessionId) || {
        claimed: 0,
        inFlight: 0
    };

    if (current.claimed >= 1) {
        return res.status(409).json({
            success: false,
            claimed: current.claimed,
            message: 'Laptop already claimed!'
        });
    }

    // Record requests that enter the race window.
    current.inFlight += 1;
    laptopClaims.set(sessionId, current);

    await new Promise(resolve => setTimeout(resolve, 200));

    // Read the latest state after the delay.
    const latest = laptopClaims.get(sessionId) || {
        claimed: 0,
        inFlight: 0
    };

    latest.claimed += 1;
    latest.inFlight = Math.max(0, latest.inFlight - 1);

    laptopClaims.set(sessionId, latest);

    const solved = latest.claimed >= 20;

    return res.json({
        success: true,
        claimed: latest.claimed,
        message: solved
            ? 'Race condition solved!'
            : 'Laptop claim successful!',
        ...(solved ? {
            flag: RACE_FLAG
        } : {})
    });
});
