import React, { useState } from 'react';

import StatCard from '../../components/user/StatCard';
import SessionCard from '../../components/user/SessionCard';
import MessageCard from '../../components/user/MessageCard';
import TimelineItem from '../../components/user/TimelineItem';
import AchievementBadge from '../../components/user/AchievementBadge';
import MilestonePoint from '../../components/user/MilestonePoint';
import HeroProfile from '../../components/user/HeroProfile';
import Sidebar from '../../components/user/Sidebar';

import { importAllUserImages } from '../../utils/importAllUserImages';
const user = importAllUserImages();

import { 
  Calendar, 
  MessageCircle, 
  TrendingUp, 
  Award,
  Github,
  Linkedin,
  Twitter,
  PlayCircle,
  Send,
  BarChart3,
  Clock,
  DollarSign,
  Target,
  Users,
  Zap,
  Activity,
  Flame,
  Menu
} from 'lucide-react';

const UserDashboard = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeItem, setActiveItem] = useState('dashboard');

  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  const userStats = [
    { icon: Users, label: 'Active Projects', value: '8', change: '+2 this week', color: 'from-blue-500 to-cyan-500' },
    { icon: Calendar, label: 'Sessions Scheduled', value: '12', change: '+3 this month', color: 'from-purple-500 to-pink-500' },
    { icon: DollarSign, label: 'Total Earnings', value: '₹45,000', change: '+15% this month', color: 'from-emerald-500 to-teal-500' },
    { icon: Target, label: 'Completion Rate', value: '92%', change: '+5% this week', color: 'from-orange-500 to-red-500' }
  ];

  const upcomingSessions = [
    {
      id: 1,
      mentorName: 'Dracule Mihawk',
      mentorImage: user['mihawk.jpg'],
      sessionTitle: 'Advanced Sword Techniques',
      date: 'Today',
      time: '3:00 PM',
      duration: '1 hour',
      status: 'confirmed',
      statusColor: 'bg-emerald-500'
    },
    {
      id: 2,
      mentorName: 'Nico Robin',
      mentorImage: user['robin.jpg'],
      sessionTitle: 'Ancient History Research',
      date: 'Tomorrow',
      time: '10:00 AM',
      duration: '2 hours',
      status: 'pending',
      statusColor: 'bg-yellow-500'
    },
    {
      id: 3,
      mentorName: 'Silvers Rayleigh',
      mentorImage: user['Rayleigh.jpg'],
      sessionTitle: 'Haki Training Fundamentals',
      date: 'Dec 22',
      time: '2:00 PM',
      duration: '3 hours',
      status: 'confirmed',
      statusColor: 'bg-emerald-500'
    }
  ];

  const recentMessages = [
    {
      id: 1,
      senderName: 'Boa Hancock',
      senderImage: user['hancock.jpg'],
      message: 'Great progress on your project! The design looks amazing.',
      timestamp: '2 mins ago',
      isOnline: true,
      isUnread: true,
      messageType: 'text'
    },
    {
      id: 2,
      senderName: 'Marco the Phoenix',
      senderImage: user['marco.jpg'],
      message: 'Ready for tomorrow\'s healing techniques session?',
      timestamp: '1 hour ago',
      isOnline: false,
      isUnread: false,
      messageType: 'text'
    },
    {
      id: 3,
      senderName: 'Portgas D. Ace',
      senderImage: user['ace.jpg'],
      message: 'Don\'t forget to bring your fire safety equipment!',
      timestamp: '3 hours ago',
      isOnline: true,
      isUnread: true,
      messageType: 'text'
    }
  ];

  const timelineItems = [
    { id: 1, icon: Award, title: 'Achievement Unlocked: Devil Fruit Master', subtitle: '2 hours ago', color: 'text-yellow-400' },
    { id: 2, icon: Calendar, title: 'New session scheduled with Admiral Kizaru', subtitle: '5 hours ago', color: 'text-blue-400' },
    { id: 3, icon: TrendingUp, title: 'Project "Grand Line Navigation" updated', subtitle: '1 day ago', color: 'text-emerald-400' },
    { id: 4, icon: Users, title: 'Session completed with Trafalgar Law', subtitle: '2 days ago', color: 'text-purple-400' }
  ];

  const achievements = [
    { 
      id: 1, 
      title: 'Pirate King', 
      description: 'Complete 100 sessions successfully', 
      achieved: true, 
      icon: '👑',
      rarity: 'legendary' 
    },
    { 
      id: 2, 
      title: 'Treasure Hunter', 
      description: 'Discover 50 hidden knowledge gems', 
      achieved: true, 
      icon: '💎',
      rarity: 'epic' 
    },
    { 
      id: 3, 
      title: 'Fleet Admiral', 
      description: 'Mentor 10 other crew members', 
      achieved: false, 
      icon: '⚓',
      rarity: 'rare' 
    },
    { 
      id: 4, 
      title: 'Devil Fruit Master', 
      description: 'Master 5 different skill areas', 
      achieved: true, 
      icon: '🌟',
      rarity: 'epic' 
    }
  ];

  const milestones = [
    { id: 1, title: "Initial Meeting", userVerified: true, mentorVerified: true },
    { id: 2, title: "Requirements", userVerified: true, mentorVerified: false },
    { id: 3, title: "Mid Review", userVerified: false, mentorVerified: false },
    { id: 4, title: "Final Submission", userVerified: false, mentorVerified: false },
    { id: 5, title: "Project Delivery", userVerified: false, mentorVerified: false }
  ];

  const quickActions = [
    { icon: Calendar, label: 'Schedule Session', color: 'from-blue-500 to-cyan-500' },
    { icon: PlayCircle, label: 'Start Adventure', color: 'from-purple-500 to-pink-500' },
    { icon: Send, label: 'Send Message', color: 'from-emerald-500 to-teal-500' },
    { icon: BarChart3, label: 'View Analytics', color: 'from-orange-500 to-red-500' }
  ];

  const userData = {
    name: "Monkey D. Luffy",
    title: "Future Pirate King",
    description: "Ready to conquer the Grand Line with knowledge and determination!",
    profileImage: user['luffy.jpg'],
    isOnline: true,
    level: 47,
    xp: 8750,
    nextLevelXp: 10000,
    location: "East Blue",
    joinDate: "May 2023",
    rating: 4.9,
    socialLinks: {
      linkedin: "#",
      github: "#",
      twitter: "#"
    },
    stats: {
      completedSessions: 156,
      totalEarnings: "₹45,000",
      streakDays: 23
    }
  };

  // Function to get the page title based on active item
  const getPageTitle = () => {
    const titles = {
      dashboard: 'Dashboard',
      projects: 'Projects',
      sessions: 'Sessions',
      messages: 'Messages',
      achievements: 'Achievements',
      analytics: 'Analytics',
      settings: 'Settings'
    };
    return titles[activeItem] || 'Dashboard';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 flex">
      {/* Sidebar */}
      <Sidebar 
        isOpen={sidebarOpen} 
        toggleSidebar={toggleSidebar} 
        activeItem={activeItem}
        setActiveItem={setActiveItem}
      />
      
      {/* Main Content */}
      <div className="flex-1 lg:ml-64">
        {/* Mobile Header */}
        <div className="lg:hidden bg-gradient-to-r from-slate-900/80 to-blue-900/80 backdrop-blur-sm border-b border-white/10 p-4">
          <div className="flex items-center justify-between">
            <button 
              onClick={toggleSidebar}
              className="text-white hover:text-gray-300 transition-colors"
            >
              <Menu size={24} />
            </button>
            <h1 className="text-xl font-bold text-white">{getPageTitle()}</h1>
            <div className="w-6"></div>
          </div>
        </div>

        {/* Animated background elements */}
        <div className="fixed inset-0 overflow-hidden pointer-events-none">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-500/20 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-purple-500/20 rounded-full blur-3xl animate-pulse"></div>
        </div>

        <div className="relative z-10 p-4 lg:p-6 space-y-6">
          
          {/* Hero Profile Section */}
          <HeroProfile user={userData} />

          {/* Stats Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 lg:gap-6">
            {userStats.map((stat, index) => (
              <StatCard key={index} {...stat} />
            ))}
          </div>

          {/* Quick Actions */}
          <div className="bg-white/10 backdrop-blur-sm rounded-3xl shadow-2xl p-6 border border-white/20 relative overflow-hidden">
            {/* Animated background elements */}
            <div className="absolute -top-10 -right-10 w-20 h-20 bg-yellow-400/20 rounded-full blur-xl animate-pulse"></div>
            <div className="absolute -bottom-10 -left-10 w-16 h-16 bg-blue-400/20 rounded-full blur-xl animate-pulse"></div>
            
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-white flex items-center">
                  <Zap className="mr-2 text-yellow-400" size={24} />
                  Quick Actions
                </h2>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full animate-ping"></div>
                  <span className="text-sm text-yellow-300 font-medium">Ready to Launch</span>
                </div>
              </div>
              
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
                {quickActions.map((action, index) => (
                  <button
                    key={index}
                    className={`group relative p-4 lg:p-6 rounded-2xl bg-gradient-to-r ${action.color} text-white hover:shadow-2xl transform hover:scale-105 transition-all duration-300 overflow-hidden`}
                  >
                    {/* Shine effect */}
                    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-1000"></div>
                    
                    {/* Content */}
                    <div className="relative z-10 flex flex-col items-center">
                      <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center mb-3 group-hover:bg-white/30 transition-colors">
                        <action.icon size={24} className="group-hover:scale-110 transition-transform" />
                      </div>
                      <span className="text-sm font-medium text-center">{action.label}</span>
                      
                      {/* Action indicator */}
                      <div className="mt-2 w-8 h-0.5 bg-white/40 rounded-full group-hover:bg-white/60 transition-colors"></div>
                    </div>
                    
                    {/* Hover glow */}
                    <div className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 shadow-lg"></div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Main Content Grid */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            
            {/* Left Column */}
            <div className="xl:col-span-2 space-y-6">
              
              {/* Upcoming Sessions */}
              <div className="bg-white/10 backdrop-blur-sm rounded-3xl shadow-2xl p-6 border border-white/20">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-bold text-white flex items-center">
                    <Clock className="mr-2 text-blue-400" size={20} />
                    Upcoming Sessions
                  </h2>
                  <Activity className="text-blue-400 animate-pulse" size={20} />
                </div>
                <div className="space-y-4">
                  {upcomingSessions.map((session) => (
                    <SessionCard key={session.id} {...session} />
                  ))}
                </div>
              </div>

              {/* Project Milestone Tracker */}
              <div className="bg-white/10 backdrop-blur-sm rounded-3xl shadow-2xl p-4 sm:p-6 border border-white/20">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 sm:mb-6 space-y-2 sm:space-y-0">
                  <h2 className="text-lg sm:text-xl font-bold text-white flex items-center">
                    <Target className="mr-2 text-purple-400" size={20} />
                    Project Milestone Tracker
                  </h2>
                  <div className="flex items-center space-x-2">
                    <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
                    <span className="text-xs sm:text-sm text-purple-300 font-medium">Live Updates</span>
                  </div>
                </div>
                
                <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 sm:mb-6 space-y-2 sm:space-y-0">
                  <div className="flex flex-col sm:flex-row sm:items-center space-y-1 sm:space-y-0 sm:space-x-4">
                    <span className="text-sm text-blue-200 font-medium">Current Project:</span>
                    <span className="text-sm sm:text-base text-white font-semibold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text ">
                      Grand Line Navigation System
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-16 sm:w-20 h-2 bg-white/20 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-purple-400 to-pink-500 rounded-full transition-all duration-500" style={{ width: '40%' }}></div>
                    </div>
                    <span className="text-sm font-bold text-purple-400">40%</span>
                  </div>
                </div>
                
                {/* Enhanced Milestone Container */}
                <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-2xl p-2 sm:p-4 border border-white/10">
                  <MilestonePoint milestones={milestones} />
                </div>
                
                {/* Additional Project Info */}
                <div className="mt-4 sm:mt-6 grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4">
                  <div className="bg-white/10 backdrop-blur-sm rounded-xl p-3 sm:p-4 text-center border border-white/20">
                    <div className="text-lg sm:text-xl font-bold text-emerald-400">
                      {milestones.filter(m => m.userVerified && m.mentorVerified).length}
                    </div>
                    <div className="text-xs sm:text-sm text-emerald-300">Completed</div>
                  </div>
                  <div className="bg-white/10 backdrop-blur-sm rounded-xl p-3 sm:p-4 text-center border border-white/20">
                    <div className="text-lg sm:text-xl font-bold text-yellow-400">
                      {milestones.filter(m => (m.userVerified || m.mentorVerified) && !(m.userVerified && m.mentorVerified)).length}
                    </div>
                    <div className="text-xs sm:text-sm text-yellow-300">In Progress</div>
                  </div>
                  <div className="bg-white/10 backdrop-blur-sm rounded-xl p-3 sm:p-4 text-center border border-white/20">
                    <div className="text-lg sm:text-xl font-bold text-slate-400">
                      {milestones.filter(m => !m.userVerified && !m.mentorVerified).length}
                    </div>
                    <div className="text-xs sm:text-sm text-slate-300">Pending</div>
                  </div>
                </div>
              </div>

              {/* Grand Line Journey */}
              <div className="bg-gradient-to-r from-orange-500/30 to-red-500/30 backdrop-blur-sm rounded-3xl p-6 text-white border border-white/20 shadow-2xl">
                <h2 className="text-xl font-bold mb-4 flex items-center">
                  <Flame className="mr-2 text-orange-400" size={20} />
                  Your Grand Line Journey
                </h2>
                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between mb-2">
                      <span className="text-white">Monthly Goals Progress</span>
                      <span className="font-bold text-orange-200">85%</span>
                    </div>
                    <div className="w-full bg-white/20 rounded-full h-3">
                      <div className="bg-gradient-to-r from-orange-400 to-red-400 h-3 rounded-full" style={{ width: '85%' }}></div>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-4">
                    <div className="text-center bg-white/10 rounded-xl p-4">
                      <div className="text-2xl font-bold text-orange-200">12</div>
                      <div className="text-sm text-orange-300">Goals Completed</div>
                    </div>
                    <div className="text-center bg-white/10 rounded-xl p-4">
                      <div className="text-2xl font-bold text-orange-200">47</div>
                      <div className="text-sm text-orange-300">Treasures Found</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Column */}
            <div className="space-y-6">
              
              {/* Recent Messages */}
              <div className="bg-white/10 backdrop-blur-sm rounded-3xl shadow-2xl p-6 border border-white/20">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-bold text-white flex items-center">
                    <MessageCircle className="mr-2 text-green-400" size={20} />
                    Recent Messages
                  </h2>
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                </div>
                <div className="space-y-4">
                  {recentMessages.map((message) => (
                    <MessageCard key={message.id} {...message} />
                  ))}
                </div>
              </div>

              {/* Activity Timeline */}
              <div className="bg-white/10 backdrop-blur-sm rounded-3xl shadow-2xl p-6 border border-white/20">
                <h2 className="text-xl font-bold text-white mb-6 flex items-center">
                  <TrendingUp className="mr-2 text-yellow-400" size={20} />
                  Activity Timeline
                </h2>
                <div className="space-y-2">
                  {timelineItems.map((item, index) => (
                    <TimelineItem 
                      key={item.id} 
                      {...item} 
                      isLast={index === timelineItems.length - 1}
                    />
                  ))}
                </div>
              </div>

              {/* Achievements */}
              <div className="bg-white/10 backdrop-blur-sm rounded-3xl shadow-2xl p-6 border border-white/20">
                <h2 className="text-xl font-bold text-white mb-6 flex items-center">
                  <Award className="mr-2 text-purple-400" size={20} />
                  Achievements
                </h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {achievements.map((achievement) => (
                    <AchievementBadge key={achievement.id} {...achievement} />
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserDashboard;