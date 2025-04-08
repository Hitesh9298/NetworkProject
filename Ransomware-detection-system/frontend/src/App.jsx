import React, { useState, useEffect } from 'react';
import { Box, Typography, Paper, List, ListItem, ListItemText, Divider, Chip, CircularProgress, Alert } from '@mui/material';
import { Warning, Error, Info } from '@mui/icons-material';
import { Line, Bar } from 'react-chartjs-2';
import axios from 'axios';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, BarElement, Title, Tooltip, Legend } from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
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
    const interval = setInterval(fetchData, 5000); // Refresh every 5 seconds

    return () => clearInterval(interval);
  }, []);

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'high':
        return <Error color="error" />;
      case 'medium':
        return <Warning color="warning" />;
      default:
        return <Info color="info" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      default:
        return 'info';
    }
  };

  const systemHealthData = {
    labels: ['CPU Usage', 'Memory Usage'],
    datasets: [
      {
        label: 'System Health',
        data: stats ? [stats.cpu, stats.memory] : [0, 0],
        backgroundColor: [
          'rgba(54, 162, 235, 0.5)',
          'rgba(255, 99, 132, 0.5)',
        ],
        borderColor: [
          'rgba(54, 162, 235, 1)',
          'rgba(255, 99, 132, 1)',
        ],
        borderWidth: 1,
      },
    ],
  };

  const networkData = {
    labels: ['Sent', 'Received'],
    datasets: [
      {
        label: 'Network Activity (MB)',
        data: stats ? [stats.network.bytes_sent / 1024 / 1024, stats.network.bytes_recv / 1024 / 1024] : [0, 0],
        backgroundColor: [
          'rgba(75, 192, 192, 0.5)',
          'rgba(153, 102, 255, 0.5)',
        ],
        borderColor: [
          'rgba(75, 192, 192, 1)',
          'rgba(153, 102, 255, 1)',
        ],
        borderWidth: 1,
      },
    ],
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
      <Typography variant="h3" gutterBottom>
        Ransomware Detection System
      </Typography>
      
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
      
      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" gutterBottom>
          Security Alerts
          <Chip 
            label={`${alerts.length} alerts`} 
            color={alerts.length > 0 ? 'error' : 'success'} 
            sx={{ ml: 2 }} 
          />
        </Typography>
        
        {alerts.length > 0 ? (
          <List>
            {alerts.map((alert, index) => (
              <React.Fragment key={index}>
                <ListItem>
                  {getSeverityIcon(alert.severity)}
                  <ListItemText
                    primary={alert.message}
                    secondary={`${alert.type.toUpperCase()} - ${new Date(alert.timestamp).toLocaleString()}`}
                    sx={{ ml: 2 }}
                  />
                  <Chip 
                    label={alert.severity} 
                    color={getSeverityColor(alert.severity)} 
                    variant="outlined" 
                  />
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