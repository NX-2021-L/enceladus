// DVP-TSK-862 fixture: two routes that share one api module.
const routeA = createRoute({ path: '/a', component: lazyRouteComponent(() => import('./A')) })
const routeB = createRoute({ path: '/b', component: lazyRouteComponent(() => import('./B')) })
const routeTree = rootRoute.addChildren([routeA, routeB])
