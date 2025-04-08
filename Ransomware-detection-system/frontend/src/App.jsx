import React, { useState, useEffect } from 'react';
import { Box, Typography, Paper, List, ListItem, ListItemText, Divider, Chip, CircularProgress, Alert, Switch, FormControlLabel, Button } from '@mui/material';
import { Warning, Error, Info, Security, Block, CheckCircle } from '@mui/icons-material';
import { Bar } from 'react-chartjs-2';
import axios from 'axios';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [blockMode, setBlockMode] = useState(true);
  const [testResults, setTestResults] = useState([]);
  const [testMode, setTestMode] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsRes, statsRes] = await Promise.all([
          axios.get('http://localhost:5000/api/alerts'),
          axios.get('http://localhost:5000/api/stats')
        ]);
        setAlerts(alertsRes.data);
        setStats(statsRes.data);
        setLoading(false);
      } catch (err) {
        setError('Failed to connect to the detection server');
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);

    return () => clearInterval(interval);
  }, []);

  const toggleBlockMode = async () => {
    try {
      const newMode = !blockMode;
      await axios.post('http://localhost:5000/api/block_mode', { enabled: newMode });
      setBlockMode(newMode);
    } catch (err) {
      console.error("Failed to update block mode:", err);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'error';
      case 'medium': return 'warning';
      default: return 'info';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'high': return <Error color="error" />;
      case 'medium': return <Warning color="warning" />;
      default: return <Info color="info" />;
    }
  };

  const getActionIcon = (action) => {
    switch (action) {
      case 'Quarantined': return <Block color="success" />;
      case 'Terminated': return <Security color="success" />;
      case 'Detected': return <CheckCircle color="info" />;
      default: return <Info color="info" />;
    }
  };

  const createTestFiles = async () => {
    try {
      const response = await axios.post('http://localhost:5000/api/test/create_files');
      setTestResults(response.data.results);
      setTestMode(true);
      // Refresh alerts after a short delay to see detection results
      setTimeout(() => {
        axios.get('http://localhost:5000/api/alerts')
          .then(res => setAlerts(res.data))
          .catch(console.error);
      }, 2000);
    } catch (error) {
      console.error("Error creating test files:", error);
    }
  };

  const cleanupTestFiles = async () => {
    try {
      await axios.post('http://localhost:5000/api/test/cleanup');
      setTestResults([]);
      setTestMode(false);
      // Refresh alerts to clear any test-related alerts
      axios.get('http://localhost:5000/api/alerts')
        .then(res => setAlerts(res.data))
        .catch(console.error);
    } catch (error) {
      console.error("Error cleaning up test files:", error);
    }
  };

  const systemHealthData = {
    labels: ['CPU Usage', 'Memory Usage'],
    datasets: [{
      label: 'System Health',
      data: stats ? [stats.cpu, stats.memory] : [0, 0],
      backgroundColor: ['rgba(54, 162, 235, 0.5)', 'rgba(255, 99, 132, 0.5)'],
      borderColor: ['rgba(54, 162, 235, 1)', 'rgba(255, 99, 132, 1)'],
      borderWidth: 1,
    }],
  };

  const networkData = {
    labels: ['Sent', 'Received'],
    datasets: [{
      label: 'Network Activity (MB)',
      data: stats ? [stats.network.bytes_sent / 1024 / 1024, stats.network.bytes_recv / 1024 / 1024] : [0, 0],
      backgroundColor: ['rgba(75, 192, 192, 0.5)', 'rgba(153, 102, 255, 0.5)'],
      borderColor: ['rgba(75, 192, 192, 1)', 'rgba(153, 102, 255, 1)'],
      borderWidth: 1,
    }],
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h3">Ransomware Detection System</Typography>
        <FormControlLabel
          control={<Switch checked={blockMode} onChange={toggleBlockMode} />}
          label={blockMode ? "Block Mode: ON" : "Block Mode: OFF"}
          labelPlacement="start"
          sx={{ ml: 0 }}
        />
      </Box>

      <Box sx={{ display: 'flex', gap: 3, mb: 3 }}>
        <Paper sx={{ p: 2, flex: 1 }}>
          <Typography variant="h6" gutterBottom>System Health</Typography>
          <Bar data={systemHealthData} />
        </Paper>
        <Paper sx={{ p: 2, flex: 1 }}>
          <Typography variant="h6" gutterBottom>Network Activity</Typography>
          <Bar data={networkData} />
        </Paper>
      </Box>

      <Paper sx={{ p: 2, mb: 3 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6">System Testing</Typography>
          <Box display="flex" gap={1}>
            <Button 
              variant="contained" 
              color="primary" 
              onClick={createTestFiles}
              disabled={testMode}
              startIcon={<Security />}
            >
              Generate Test Files
            </Button>
            <Button 
              variant="outlined" 
              color="secondary" 
              onClick={cleanupTestFiles}
              disabled={!testMode}
              startIcon={<Block />}
            >
              Cleanup Test Files
            </Button>
          </Box>
        </Box>

        {testResults.length > 0 && (
          <Box>
            <Typography variant="subtitle1" gutterBottom>Test Files Created:</Typography>
            <List dense>
              {testResults.map((result, index) => (
                <ListItem key={index}>
                  <ListItemText
                    primary={result.filename}
                    secondary={
                      result.status 
                        ? `Type: ${result.type} - Should detect: ${result.should_detect}`
                        : `Error: ${result.error}`
                    }
                  />
                  {result.status && (
                    <Chip 
                      label={result.should_detect ? "Should Detect" : "Should Ignore"} 
                      color={result.should_detect ? "warning" : "success"} 
                      variant="outlined"
                    />
                  )}
                </ListItem>
              ))}
            </List>
          </Box>
        )}
      </Paper>

      <Paper sx={{ p: 2 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6">Security Alerts</Typography>
          <Chip 
            label={`${alerts.length} alerts`} 
            color={alerts.length > 0 ? 'error' : 'success'} 
            sx={{ ml: 2 }} 
          />
        </Box>
        
        {alerts.length > 0 ? (
          <List>
            {alerts.map((alert, index) => (
              <React.Fragment key={index}>
                <ListItem>
                  {getSeverityIcon(alert.severity)}
                  <ListItemText
                    primary={alert.message}
                    secondary={
                      <>
                        {`${alert.type.toUpperCase()} - ${new Date(alert.timestamp).toLocaleString()}`}
                        <br />
                        {`Action: ${alert.action_taken || 'None'}`}
                      </>
                    }
                    sx={{ ml: 2 }}
                  />
                  <Box display="flex" alignItems="center" gap={1}>
                    <Chip 
                      label={alert.severity} 
                      color={getSeverityColor(alert.severity)} 
                      variant="outlined" 
                    />
                    {getActionIcon(alert.action_taken)}
                  </Box>
                </ListItem>
                {index < alerts.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>
        ) : (
          <Alert severity="success">No security alerts detected</Alert>
        )}
      </Paper>
    </Box>
  );
}

export default App;